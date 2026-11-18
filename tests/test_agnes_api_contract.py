"""Agnes 3.0 Flash request fields match its published Chat Completions API."""
import json

import pytest

from winre import llm_client


def test_agnes_reasoning_uses_documented_chat_template_extension(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")
    monkeypatch.delenv("WINRE_LLM_TIMEOUT", raising=False)

    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": True},
    }
    assert llm_client.chat_openai_options(4096) == {
        "timeout": 120,
        "extra_body": {
            "max_tokens": 4096,
            "chat_template_kwargs": {"enable_thinking": True},
        },
    }


def test_request_timeout_is_configurable_and_validated(monkeypatch):
    monkeypatch.delenv("WINRE_LLM_TIMEOUT", raising=False)
    assert llm_client.request_timeout() == 120
    monkeypatch.setenv("WINRE_LLM_TIMEOUT", "600")
    assert llm_client.request_timeout() == 600
    assert llm_client.chat_openai_options(4096)["timeout"] == 600
    assert llm_client.request_timeout(45) == 45
    for invalid in ("slow", "0", "3601"):
        with pytest.raises(ValueError, match="WINRE_LLM_TIMEOUT"):
            llm_client.request_timeout(invalid)


@pytest.mark.parametrize("legacy_level", ["low", "medium", "high", "max"])
def test_agnes_legacy_effort_levels_are_all_thinking_on_aliases(
        monkeypatch, legacy_level):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", legacy_level)
    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": True},
    }


def test_agnes_enabled_is_canonical_thinking_on_value(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "enabled")
    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": True},
    }


def test_agnes_defaults_to_thinking_on_when_setting_is_blank(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "")
    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": True},
    }


def test_agnes_disabled_reasoning_uses_supported_boolean(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "disabled")

    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": False},
    }


def test_non_agnes_reasoning_contract_is_unchanged(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")
    monkeypatch.delenv("WINRE_LLM_TIMEOUT", raising=False)

    assert llm_client._reasoning_field() == {"reasoning_effort": "high"}
    # The urllib path merges _reasoning_field() into every payload; the
    # LangChain path now carries the same field through extra_body so
    # WINRE_LLM_REASONING is not silently inert there.
    assert llm_client.chat_openai_options(4096) == {
        "max_tokens": 4096, "timeout": 120,
        "extra_body": {"reasoning_effort": "high"}}
    monkeypatch.setattr(llm_client, "REASONING", "enabled")
    assert llm_client._reasoning_field() == {}
    assert llm_client.chat_openai_options(4096) == {
        "max_tokens": 4096, "timeout": 120}


def test_stepfun_reasoning_effort_reaches_the_langchain_path(monkeypatch):
    """StepFun step_plan endpoint: reasoning_effort low/medium/high is the
    documented Chat Completions control and step-5-preview defaults to HIGH
    when the field is absent, so the configured effort must never be dropped."""
    monkeypatch.setattr(llm_client, "BASE_URL",
                        "https://api.stepfun.ai/step_plan/v1")
    monkeypatch.delenv("WINRE_LLM_TIMEOUT", raising=False)

    monkeypatch.setattr(llm_client, "REASONING", "low")
    assert llm_client._reasoning_field() == {"reasoning_effort": "low"}
    assert llm_client.chat_openai_options(4096) == {
        "max_tokens": 4096, "timeout": 120,
        "extra_body": {"reasoning_effort": "low"}}
    monkeypatch.setattr(llm_client, "REASONING", "medium")
    assert llm_client._reasoning_field() == {"reasoning_effort": "medium"}
    monkeypatch.setattr(llm_client, "REASONING", "high")
    assert llm_client._reasoning_field() == {"reasoning_effort": "high"}
    # enabled/disabled aliases keep the provider default (no documented off).
    monkeypatch.setattr(llm_client, "REASONING", "enabled")
    assert llm_client.chat_openai_options(4096) == {
        "max_tokens": 4096, "timeout": 120}


def test_agnes_output_cap_is_enforced_only_for_agnes(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    assert llm_client.max_output_tokens(100000) == 65536
    assert llm_client.max_output_tokens(4096) == 4096

    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    assert llm_client.max_output_tokens(100000) == 100000


def test_explicit_langchain_endpoint_controls_reasoning_field(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")
    monkeypatch.delenv("WINRE_LLM_TIMEOUT", raising=False)

    assert llm_client.chat_openai_options(
        4096, "https://apihub.agnes-ai.com/v1") == {
            "timeout": 120,
            "extra_body": {
                "max_tokens": 4096,
                "chat_template_kwargs": {"enable_thinking": True},
            },
        }


def test_provider_context_limit_bounds_evidence_budget(monkeypatch):
    from winre.agentic import _ctx_budget_chars

    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setenv("WINRE_LLM_CONTEXT_TOKENS", "1000000")
    assert llm_client.context_window_tokens() == 512000
    assert _ctx_budget_chars() < 512000 * 3.6

    monkeypatch.setenv("WINRE_LLM_CONTEXT_TOKENS", "10000")
    assert llm_client.context_window_tokens() == 10000
    assert _ctx_budget_chars() < 10000 * 3.6

    monkeypatch.setenv("WINRE_LLM_CONTEXT_TOKENS", "1000000")
    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    assert llm_client.context_window_tokens() == 1000000


def test_chat_request_uses_documented_payload(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")
    monkeypatch.setattr(llm_client, "MODEL", "configured-llm")
    monkeypatch.setattr(llm_client, "API_KEY", "test-key")
    monkeypatch.setenv("WINRE_LLM_TIMEOUT", "600")
    requests = []
    timeouts = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "OK"}}]}).encode()

    def urlopen(request, timeout):
        requests.append(request)
        timeouts.append(timeout)
        return Response()

    monkeypatch.setattr(llm_client.urllib.request, "urlopen", urlopen)
    assert llm_client.chat([{"role": "user", "content": "probe"}],
                           max_tokens=100000) == "OK"
    assert timeouts == [600]
    assert requests[0].full_url == "https://apihub.agnes-ai.com/v1/chat/completions"
    body = json.loads(requests[0].data)
    assert body["max_tokens"] == 65536
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert "reasoning_effort" not in body
    assert "thinking" not in body


def test_langchain_serializes_documented_token_field(monkeypatch):
    httpx = pytest.importorskip("httpx")
    ChatOpenAI = pytest.importorskip("langchain_openai").ChatOpenAI
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")
    monkeypatch.setenv("WINRE_LLM_TIMEOUT", "600")
    bodies = []
    request_timeouts = []

    def handle(request):
        bodies.append(json.loads(request.content))
        request_timeouts.append(request.extensions.get("timeout"))
        return httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "created": 0,
            "model": "configured-llm",
            "choices": [{"index": 0, "message": {
                "role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
        })

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        model = ChatOpenAI(
            model="configured-llm", api_key="test-key", http_client=client,
            base_url="https://apihub.agnes-ai.com/v1", temperature=0,
            **llm_client.chat_openai_options(100000),
        )
        model.bind_tools([{"type": "function", "function": {
            "name": "probe", "description": "Contract probe",
            "parameters": {"type": "object", "properties": {}},
        }}]).invoke("Contract probe")

    body = bodies[0]
    assert request_timeouts[0]["read"] == 600
    assert body["max_tokens"] == 65536
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert body["tools"]
    assert set(body) <= {
        "model", "messages", "temperature", "top_p", "max_tokens", "stream",
        "tools", "tool_choice", "chat_template_kwargs",
    }


# ---------------------------------------------------------------- RC-80
# The provider intermittently returns a response with neither text nor tool
# calls (12 events in one RevAI publish stage, 2026-11-18; WinRE's claim
# review failed closed on the same class). The endpoint documents no
# reasoning off switch, so a bounded same-effort retry is the correct
# recovery -- mirrors RevAI RC-79. Fail closed after the bound.
def test_an_empty_response_is_retried_at_the_same_settings(monkeypatch):
    posts = []

    def fake_post(path, payload, timeout=120):
        posts.append(payload)
        if len(posts) == 1:
            return {"choices": [{"message": {"role": "assistant", "content": ""},
                                 "finish_reason": "stop"}], "usage": {}}
        return {"choices": [{"message": {"role": "assistant",
                                         "content": '{"ok":true}'},
                             "finish_reason": "stop"}], "usage": {}}

    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setattr(llm_client.time, "sleep", lambda *_a: None)

    out = llm_client.chat_result([{"role": "user", "content": "ping"}])

    assert out["content"] == '{"ok":true}'
    assert len(posts) == 2, "the same-effort retry must fire"
    # Both attempts send the identical payload (same effort, same settings).
    assert posts[0] == posts[1]


def test_an_always_empty_response_fails_closed_after_the_bound(monkeypatch):
    posts = []

    def fake_post(path, payload, timeout=120):
        posts.append(payload)
        return {"choices": [{"message": {"role": "assistant", "content": ""},
                             "finish_reason": "stop"}], "usage": {}}

    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setattr(llm_client.time, "sleep", lambda *_a: None)

    try:
        llm_client.chat_result([{"role": "user", "content": "ping"}])
        raise AssertionError("an always-empty response must raise LLMError")
    except llm_client.LLMError as e:
        assert "missing content" in str(e)
    assert len(posts) == llm_client._EMPTY_RESPONSE_MAX_RETRIES + 1, (
        "the retry bound must hold")


def test_a_malformed_response_is_not_retried(monkeypatch):
    """Structurally broken responses fail closed immediately (no retry)."""
    posts = []

    def fake_post(path, payload, timeout=120):
        posts.append(payload)
        return {"error": {"message": "no choices here"}}

    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setattr(llm_client.time, "sleep", lambda *_a: None)

    try:
        llm_client.chat_result([{"role": "user", "content": "ping"}])
        raise AssertionError("a malformed response must raise LLMError")
    except llm_client.LLMError:
        pass
    assert len(posts) == 1, "a malformed response must not be retried"


def test_a_tool_call_response_is_usable_without_text(monkeypatch):
    posts = []

    def fake_post(path, payload, timeout=120):
        posts.append(payload)
        return {"choices": [{"message": {"role": "assistant", "content": None,
                                         "tool_calls": [{"id": "c1"}]},
                             "finish_reason": "tool_calls"}], "usage": {}}

    monkeypatch.setattr(llm_client, "_post", fake_post)

    out = llm_client.chat_result([{"role": "user", "content": "ping"}])
    assert out["tool_calls"] == [{"id": "c1"}]
    assert len(posts) == 1, "a tool-call response is usable; no retry"
