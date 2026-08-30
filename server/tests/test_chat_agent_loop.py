"""Agent-loop tests for the OpenAI-compatible chat agent.

These guard the three things that changed when the backend moved from Ollama's
native API to vLLM, all of which are invisible until a *second* request is sent
on the same conversation:

  * server-only fields (reasoning_content) must not be replayed as input
  * every assistant tool_call id must be answered by a matching tool message
  * tool arguments arrive as a JSON string, not a dict

The conversation store caches history for an hour, so a malformed turn breaks a
thread long after the request that caused it — hence the emphasis on asserting
the *outbound* body of the follow-up request.
"""

import json

import httpx
import pytest

from ghidra_assist import chat_agent


@pytest.fixture(autouse=True)
def _clear_conversations():
    chat_agent._conversations.clear()
    yield
    chat_agent._conversations.clear()


def _install_transport(monkeypatch, *responses):
    """Route every httpx.AsyncClient through a MockTransport.

    Each response is a dict (HTTP 200) or a ``(status, body)`` tuple; the last
    repeats. Returns the list that captures outbound requests.
    """
    captured: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        status, body = item if isinstance(item, tuple) else (200, item)
        return httpx.Response(status, json=body)

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return captured


def _stub_tools(monkeypatch, result):
    """Give the agent one tool schema and a canned execution result."""
    monkeypatch.setattr(
        chat_agent,
        "_build_tool_schemas",
        lambda: [
            {
                "type": "function",
                "function": {
                    "name": "list_functions",
                    "description": "list functions",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    )

    async def _fake_execute(tool_name, arguments):
        return result

    monkeypatch.setattr(chat_agent, "_execute_tool_call", _fake_execute)


def _tool_call(call_id, name="list_functions", arguments='{"repository": "fw"}'):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }


def _completion(content=None, tool_calls=None, **extra):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    message.update(extra)
    return {"choices": [{"message": message, "finish_reason": "stop"}]}


def _assert_valid_history(messages):
    """Every assistant tool_call id must be answered, in order, by a tool msg.

    This is exactly what vLLM enforces and Ollama did not.
    """
    pending: list[str] = []
    for msg in messages:
        role = msg.get("role")
        if role == "assistant":
            assert not pending, f"unanswered tool calls before new assistant: {pending}"
            pending = [tc["id"] for tc in msg.get("tool_calls") or []]
        elif role == "tool":
            assert "tool_call_id" in msg, "tool message missing tool_call_id"
            assert msg["tool_call_id"] in pending, (
                f"tool_call_id {msg['tool_call_id']} answers no pending call"
            )
            pending.remove(msg["tool_call_id"])
        elif role == "user":
            assert not pending, f"user message interleaved with pending calls: {pending}"
    assert not pending, f"conversation ends with unanswered tool calls: {pending}"


@pytest.mark.asyncio
async def test_round_trip_strips_server_fields_and_answers_every_tool_call(monkeypatch):
    """The follow-up request must carry a legal, fully-answered history."""
    captured = _install_transport(
        monkeypatch,
        _completion(
            content=None,
            tool_calls=[_tool_call("call_1")],
            reasoning_content="internal monologue the server should not get back",
        ),
        _completion(content="There are 12 functions."),
    )
    _stub_tools(monkeypatch, {"functions": ["main", "init"]})

    result = await chat(message="how many functions?", monkeypatch=None)

    assert result["response"] == "There are 12 functions."
    assert len(captured) == 2

    sent = json.loads(captured[1].read())["messages"]

    # reasoning_content is valid output but illegal as input — must be gone.
    assert all("reasoning_content" not in m for m in sent)

    assistant = [m for m in sent if m.get("role") == "assistant"][0]
    tool_msgs = [m for m in sent if m.get("role") == "tool"]
    assert assistant["tool_calls"][0]["id"] == "call_1"
    assert len(tool_msgs) == 1
    assert tool_msgs[0]["tool_call_id"] == "call_1"

    _assert_valid_history(sent)


@pytest.mark.asyncio
async def test_json_string_arguments_reach_the_tool_as_a_dict(monkeypatch):
    """The core Ollama -> OpenAI difference: arguments is a string."""
    _install_transport(
        monkeypatch,
        _completion(tool_calls=[_tool_call("call_1", arguments='{"repository": "fw"}')]),
        _completion(content="done"),
    )
    monkeypatch.setattr(chat_agent, "_build_tool_schemas", lambda: [])

    seen: list = []

    async def _capture(tool_name, arguments):
        seen.append(arguments)
        return {"ok": True}

    monkeypatch.setattr(chat_agent, "_execute_tool_call", _capture)

    await chat(message="list them")

    assert seen == [{"repository": "fw"}]


@pytest.mark.asyncio
async def test_multiple_tool_calls_in_one_batch_are_all_answered(monkeypatch):
    captured = _install_transport(
        monkeypatch,
        _completion(tool_calls=[_tool_call("call_1"), _tool_call("call_2")]),
        _completion(content="both done"),
    )
    _stub_tools(monkeypatch, {"ok": True})

    await chat(message="do two things")

    sent = json.loads(captured[1].read())["messages"]
    tool_ids = [m["tool_call_id"] for m in sent if m.get("role") == "tool"]
    assert tool_ids == ["call_1", "call_2"]
    _assert_valid_history(sent)


@pytest.mark.asyncio
async def test_loop_detection_abort_leaves_a_valid_history(monkeypatch):
    """The old code broke mid-batch, leaving a tool call unanswered forever.

    Because the history is cached for an hour, that poisoned every later message
    on the same conversation. The abort nudge must come *after* the batch.
    """
    _install_transport(
        monkeypatch,
        # Same failing call twice in a row trips the loop detector.
        _completion(tool_calls=[_tool_call("call_1")]),
        _completion(tool_calls=[_tool_call("call_2")]),
        _completion(content="giving up"),
    )
    _stub_tools(monkeypatch, {"error": "tool unavailable in this environment"})

    conversation_id = "abort-test"
    await chat(message="try it", conversation_id=conversation_id)

    history = chat_agent._conversations[conversation_id]["messages"]
    _assert_valid_history(history)

    # The nudge is present, and lands after the tool results rather than
    # replacing them.
    assert any(
        m.get("role") == "user" and "stop calling tools" in (m.get("content") or "")
        for m in history
    )


@pytest.mark.asyncio
async def test_http_400_retries_once_without_tools(monkeypatch):
    """vLLM without --enable-auto-tool-choice returns 400 for a tools payload."""
    captured = _install_transport(
        monkeypatch,
        (400, {"error": "tool use is not enabled"}),
        _completion(content="answered without tools"),
    )
    _stub_tools(monkeypatch, {"ok": True})

    result = await chat(message="hello")

    assert result["response"] == "answered without tools"
    assert len(captured) == 2, "expected exactly one retry, no recursion"

    first = json.loads(captured[0].read())
    second = json.loads(captured[1].read())
    assert "tools" in first
    assert "tools" not in second


# ---------------------------------------------------------------------------
# Helper: call chat() with the arguments these tests share
# ---------------------------------------------------------------------------


async def chat(message, conversation_id=None, **_ignored):
    return await chat_agent.chat(
        message=message,
        context=None,
        conversation_id=conversation_id or "test-conversation",
        max_turns=4,
    )
