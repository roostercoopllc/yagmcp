"""Tests for the OpenAI-compatible LLM client helpers.

Vendored copy — keep in sync with:
    home-automation/mcp/tests/test_llm_client.py

Everything here runs against ``httpx.MockTransport``, so the suite passes with
no LLM endpoint reachable — which matters because the DGX Sparks are often
powered down.
"""

import httpx
import pytest

from ghidra_assist.llm_client import (
    build_headers,
    chat_completion,
    extract_message,
    list_models,
    normalize_assistant_message,
    normalize_base_url,
    parse_tool_arguments,
    tool_result_message,
)


def _make_client(*responses):
    """Build a client backed by MockTransport.

    Each response is a dict (sent with HTTP 200) or a ``(status, body)`` tuple.
    The final response repeats if more requests arrive than were queued.
    Returns ``(client, captured_requests)``.
    """
    captured: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        status, body = item if isinstance(item, tuple) else (200, item)
        return httpx.Response(status, json=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), captured


def _completion(content=None, tool_calls=None, **extra):
    """Build an OpenAI-shaped chat-completions response body."""
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    message.update(extra)
    return {"choices": [{"message": message, "finish_reason": "stop"}]}


# ---------------------------------------------------------------------------
# normalize_base_url
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "http://192.168.0.25:8001",
        "http://192.168.0.25:8001/",
        "http://192.168.0.25:8001/v1",
        "http://192.168.0.25:8001/v1/",
        "  http://192.168.0.25:8001/v1  ",
    ],
)
def test_normalize_base_url_accepts_every_spelling(raw):
    """A trailing slash or missing /v1 in a ConfigMap must not cause a 404."""
    assert normalize_base_url(raw) == "http://192.168.0.25:8001/v1"


@pytest.mark.parametrize("raw", ["", "   ", None])
def test_normalize_base_url_rejects_empty(raw):
    with pytest.raises(ValueError):
        normalize_base_url(raw)


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_posts_to_chat_completions_with_bearer_token():
    client, captured = _make_client(_completion("hi"))
    async with client:
        await chat_completion(
            client,
            base_url="http://192.168.0.25:8001",
            api_key="secret",
            model="maverick",
            messages=[{"role": "user", "content": "hello"}],
        )

    assert len(captured) == 1
    assert str(captured[0].url) == "http://192.168.0.25:8001/v1/chat/completions"
    assert captured[0].headers["authorization"] == "Bearer secret"


@pytest.mark.asyncio
async def test_omits_auth_header_when_no_key_configured():
    """vLLM without --api-key rejects nothing, but sending 'Bearer ' is sloppy."""
    client, captured = _make_client(_completion("hi"))
    async with client:
        await chat_completion(
            client,
            base_url="http://192.168.0.25:8001/v1",
            api_key="",
            model="maverick",
            messages=[{"role": "user", "content": "hello"}],
        )

    assert "authorization" not in captured[0].headers


def test_build_headers_omits_authorization_for_falsy_key():
    assert "Authorization" not in build_headers("")
    assert "Authorization" not in build_headers(None)
    assert build_headers("k")["Authorization"] == "Bearer k"


@pytest.mark.asyncio
async def test_empty_tools_list_is_omitted_entirely():
    """Some vLLM builds return 400 for "tools": [] — send no key at all."""
    client, captured = _make_client(_completion("hi"))
    async with client:
        await chat_completion(
            client,
            base_url="http://192.168.0.25:8001/v1",
            api_key="",
            model="maverick",
            messages=[{"role": "user", "content": "hello"}],
            tools=[],
        )

    body = captured[0].read().decode()
    assert "tools" not in body
    assert "tool_choice" not in body


@pytest.mark.asyncio
async def test_tools_are_sent_with_explicit_tool_choice():
    import json

    schema = [{"type": "function", "function": {"name": "get_status"}}]
    client, captured = _make_client(_completion("hi"))
    async with client:
        await chat_completion(
            client,
            base_url="http://192.168.0.25:8001/v1",
            api_key="",
            model="maverick",
            messages=[{"role": "user", "content": "hello"}],
            tools=schema,
            max_tokens=256,
            temperature=0.2,
        )

    payload = json.loads(captured[0].read())
    assert payload["tools"] == schema
    assert payload["tool_choice"] == "auto"
    assert payload["max_tokens"] == 256
    assert payload["temperature"] == 0.2
    assert payload["stream"] is False


@pytest.mark.asyncio
async def test_raises_http_status_error_so_callers_can_inspect_400():
    """The no-tools retry in chat_agent keys off the 400/422 status code."""
    client, _ = _make_client((400, {"error": "tool use not enabled"}))
    async with client:
        with pytest.raises(httpx.HTTPStatusError) as exc:
            await chat_completion(
                client,
                base_url="http://192.168.0.25:8001/v1",
                api_key="",
                model="maverick",
                messages=[{"role": "user", "content": "hello"}],
                tools=[{"type": "function", "function": {"name": "x"}}],
            )
    assert exc.value.response.status_code == 400


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_extract_message_reads_openai_shape():
    assert extract_message(_completion("hello"))["content"] == "hello"


def test_extract_message_tolerates_empty_choices():
    assert extract_message({"choices": []}) == {}
    assert extract_message({}) == {}


def test_normalize_assistant_message_strips_server_only_fields():
    """reasoning_content and friends are valid output but illegal as input."""
    raw = {
        "role": "assistant",
        "content": "thinking done",
        "reasoning_content": "long internal monologue",
        "refusal": None,
        "annotations": [],
    }
    normalized = normalize_assistant_message(raw)

    assert normalized == {"role": "assistant", "content": "thinking done"}


def test_normalize_assistant_message_keeps_arguments_as_string():
    """Arguments must be replayed verbatim as a JSON string, not re-encoded."""
    raw = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_abc",
                "type": "function",
                "function": {"name": "get_status", "arguments": '{"host": "xps"}'},
            }
        ],
    }
    normalized = normalize_assistant_message(raw)

    assert normalized["tool_calls"][0]["id"] == "call_abc"
    assert normalized["tool_calls"][0]["function"]["arguments"] == '{"host": "xps"}'


def test_normalize_assistant_message_omits_empty_tool_calls():
    normalized = normalize_assistant_message({"role": "assistant", "content": "hi"})
    assert "tool_calls" not in normalized


# ---------------------------------------------------------------------------
# parse_tool_arguments
# ---------------------------------------------------------------------------


def test_parse_tool_arguments_decodes_json_string():
    """This is the core Ollama -> OpenAI difference: a string, not a dict."""
    assert parse_tool_arguments('{"host": "xps", "n": 3}') == {"host": "xps", "n": 3}


def test_parse_tool_arguments_passes_dicts_through():
    """The text-fallback parsers in chat_agent produce dicts already."""
    assert parse_tool_arguments({"host": "xps"}) == {"host": "xps"}


@pytest.mark.parametrize("raw", ["not json at all", "", "   ", None, 42, "[1, 2]"])
def test_parse_tool_arguments_never_raises(raw):
    """A malformed tool call should surface as a tool error, not crash the loop."""
    assert parse_tool_arguments(raw) == {}


# ---------------------------------------------------------------------------
# tool_result_message
# ---------------------------------------------------------------------------


def test_tool_result_message_carries_tool_call_id_and_json_content():
    import json

    msg = tool_result_message("call_abc", {"ok": True, "value": None})

    assert msg["role"] == "tool"
    assert msg["tool_call_id"] == "call_abc"
    # json.dumps, not str() — str() would emit Python repr (True/None/quotes).
    assert json.loads(msg["content"]) == {"ok": True, "value": None}


def test_tool_result_message_serialises_non_json_types():
    """default=str keeps unusual tool return values from raising."""
    import datetime
    import json

    msg = tool_result_message("c1", {"when": datetime.date(2026, 8, 29)})
    assert json.loads(msg["content"])["when"] == "2026-08-29"


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_models_parses_openai_data_ids():
    """/v1/models returns data[].id, not Ollama's models[].name."""
    body = {"data": [{"id": "RedHatAI/Llama-4-Maverick"}, {"id": "other"}]}
    client, captured = _make_client(body)
    async with client:
        models = await list_models(
            client, base_url="http://192.168.0.25:8001", api_key="k"
        )

    assert models == ["RedHatAI/Llama-4-Maverick", "other"]
    assert str(captured[0].url) == "http://192.168.0.25:8001/v1/models"


@pytest.mark.asyncio
async def test_list_models_skips_malformed_entries():
    client, _ = _make_client({"data": [{"id": "good"}, {}, "junk", {"id": ""}]})
    async with client:
        assert await list_models(
            client, base_url="http://192.168.0.25:8001/v1", api_key=""
        ) == ["good"]
