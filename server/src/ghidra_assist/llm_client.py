"""OpenAI-compatible LLM client helpers (vLLM / NIM).

Vendored copy — keep in sync with:
    home-automation/mcp/src/home_automation_mcp/llm_client.py

Small dependency-free helpers over ``httpx`` for talking to an OpenAI-compatible
chat-completions endpoint. This deliberately does *not* own the agent loop: the
two callers that use it differ too much (conversation stores, client-side
directives, tool filters) for a shared loop to be worth the coupling.

``chat_completion`` takes an injected ``httpx.AsyncClient`` so each caller keeps
its own timeout policy, and so tests can supply an ``httpx.MockTransport``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def normalize_base_url(url: str) -> str:
    """Return ``url`` as a ``/v1`` root, accepting it with or without the suffix.

    Tolerates ``http://host:8001``, ``.../v1`` and ``.../v1/`` alike so a
    trailing slash in a ConfigMap can't silently produce a 404.
    """
    cleaned = (url or "").strip().rstrip("/")
    if not cleaned:
        raise ValueError("LLM base URL is empty")
    if not cleaned.endswith("/v1"):
        cleaned = f"{cleaned}/v1"
    return cleaned


def build_headers(api_key: str | None) -> dict[str, str]:
    """Build request headers, omitting auth entirely when no key is configured."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


async def chat_completion(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    api_key: str | None,
    model: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> dict:
    """POST to ``/v1/chat/completions`` and return the decoded response body.

    Raises ``httpx.HTTPStatusError`` on a non-2xx response so callers can
    inspect the status (notably 400/422, which signals a server without
    ``--enable-auto-tool-choice``).
    """
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
    }
    # An empty tools list makes some vLLM builds return 400 — omit it entirely.
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    if temperature is not None:
        payload["temperature"] = temperature

    response = await client.post(
        f"{normalize_base_url(base_url)}/chat/completions",
        json=payload,
        headers=build_headers(api_key),
    )
    response.raise_for_status()
    return response.json()


def extract_message(data: dict) -> dict:
    """Pull the assistant message out of an OpenAI-shaped response body."""
    choices = data.get("choices") or []
    if not choices:
        logger.warning("LLM response contained no choices")
        return {}
    message = choices[0].get("message")
    return message if isinstance(message, dict) else {}


def normalize_assistant_message(message: dict) -> dict:
    """Reduce a server assistant message to the fields that are legal as *input*.

    vLLM/NIM attach ``reasoning_content``, ``refusal``, ``annotations`` and
    similar depending on version and model. Those are valid output but are
    rejected or ignored when replayed in a later request, and both callers
    append the assistant message straight back into the conversation — so strip
    everything except role, content and tool calls before storing.
    """
    normalized: dict[str, Any] = {
        "role": "assistant",
        "content": message.get("content"),
    }

    tool_calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        tool_calls.append(
            {
                "id": call.get("id"),
                "type": "function",
                "function": {
                    "name": function.get("name", ""),
                    # Kept verbatim as a JSON string — that is the shape the API
                    # expects on the way back in.
                    "arguments": function.get("arguments", ""),
                },
            }
        )
    if tool_calls:
        normalized["tool_calls"] = tool_calls

    return normalized


def parse_tool_arguments(raw: Any) -> dict:
    """Coerce a tool call's ``arguments`` into a dict.

    OpenAI-compatible servers send a JSON *string*; the callers' text-fallback
    parsers produce a dict already. Malformed JSON yields an empty dict rather
    than raising — a bad tool call should surface as a tool error, not crash the
    whole agent loop.
    """
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        logger.warning("Could not parse tool arguments as JSON: %.200s", raw)
        return {}
    return parsed if isinstance(parsed, dict) else {}


def tool_result_message(tool_call_id: str, result: Any) -> dict:
    """Build the ``role: tool`` reply that answers one tool call.

    Every ``tool_call`` id in an assistant message must be answered before the
    next request or the server rejects the conversation, so callers must emit
    one of these per call with nothing interleaved.
    """
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": json.dumps(result, default=str),
    }


async def list_models(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    api_key: str | None,
) -> list[str]:
    """GET ``/v1/models`` and return the served model ids."""
    response = await client.get(
        f"{normalize_base_url(base_url)}/models",
        headers=build_headers(api_key),
    )
    response.raise_for_status()
    data = response.json()
    return [
        entry["id"]
        for entry in data.get("data", [])
        if isinstance(entry, dict) and entry.get("id")
    ]
