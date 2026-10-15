"""Agnes 3.0 Flash request fields match its published Chat Completions API."""
import json

import pytest

from winre import llm_client


def test_agnes_reasoning_uses_documented_chat_template_extension(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")

    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": True},
    }
    assert llm_client.chat_openai_options(4096) == {"extra_body": {
        "max_tokens": 4096, "chat_template_kwargs": {"enable_thinking": True}}}


def test_agnes_disabled_reasoning_uses_supported_boolean(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    monkeypatch.setattr(llm_client, "REASONING", "disabled")

    assert llm_client._reasoning_field() == {
        "chat_template_kwargs": {"enable_thinking": False},
    }


def test_non_agnes_reasoning_contract_is_unchanged(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")

    assert llm_client._reasoning_field() == {"reasoning_effort": "high"}
    assert llm_client.chat_openai_options(4096) == {"max_tokens": 4096}


def test_agnes_output_cap_is_enforced_only_for_agnes(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://apihub.agnes-ai.com/v1")
    assert llm_client.max_output_tokens(100000) == 65536
    assert llm_client.max_output_tokens(4096) == 4096

    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    assert llm_client.max_output_tokens(100000) == 100000


def test_explicit_langchain_endpoint_controls_reasoning_field(monkeypatch):
    monkeypatch.setattr(llm_client, "BASE_URL", "https://provider.example/v1")
    monkeypatch.setattr(llm_client, "REASONING", "high")

    assert llm_client.chat_openai_options(
        4096, "https://apihub.agnes-ai.com/v1") == {"extra_body": {
            "max_tokens": 4096,
            "chat_template_kwargs": {"enable_thinking": True}}}


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
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "OK"}}]}).encode()

    def urlopen(request, timeout):
        requests.append(request)
        return Response()

    monkeypatch.setattr(llm_client.urllib.request, "urlopen", urlopen)
    assert llm_client.chat([{"role": "user", "content": "probe"}],
                           max_tokens=100000) == "OK"
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
    bodies = []

    def handle(request):
        bodies.append(json.loads(request.content))
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
    assert body["max_tokens"] == 65536
    assert body["chat_template_kwargs"] == {"enable_thinking": True}
    assert body["tools"]
    assert set(body) <= {
        "model", "messages", "temperature", "top_p", "max_tokens", "stream",
        "tools", "tool_choice", "chat_template_kwargs",
    }
