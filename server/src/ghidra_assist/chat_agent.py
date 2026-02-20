"""Ollama-powered chat agent with MCP tool calling.

Receives a user message with optional reverse-engineering context,
sends it to Ollama with available Ghidra-Assist tools in function-calling
format, executes any tool calls against the MCP tool registry, and
returns the final response.

Usage:
    from ghidra_assist.chat_agent import chat

    result = await chat(
        message="What does the function at 0x401000 do?",
        context={"repo": "firmware", "program": "main.bin"},
        conversation_id="abc123",
    )
"""

from __future__ import annotations

import inspect
import logging
import time
import uuid
from collections import OrderedDict
from typing import Any

import httpx

from .config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory conversation store with TTL
# ---------------------------------------------------------------------------

_MAX_CONVERSATIONS = 100
_CONVERSATION_TTL_SECONDS = 3600  # 1 hour

_conversations: OrderedDict[str, dict] = OrderedDict()


def _get_conversation(conversation_id: str) -> list[dict]:
    """Retrieve or create a conversation's message list."""
    now = time.monotonic()

    # Evict expired conversations
    expired = [
        cid
        for cid, conv in _conversations.items()
        if now - conv["last_used"] > _CONVERSATION_TTL_SECONDS
    ]
    for cid in expired:
        _conversations.pop(cid, None)

    if conversation_id in _conversations:
        entry = _conversations[conversation_id]
        entry["last_used"] = now
        _conversations.move_to_end(conversation_id)
        return entry["messages"]

    # Create new conversation
    if len(_conversations) >= _MAX_CONVERSATIONS:
        _conversations.popitem(last=False)  # evict oldest

    messages: list[dict] = []
    _conversations[conversation_id] = {"messages": messages, "last_used": now}
    return messages


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert reverse engineering assistant integrated with Ghidra.
You have access to tools that can list functions, decompile code,
read memory, find cross-references, list strings, and more.

When answering questions:
- Use the available tools to look up concrete data before speculating.
- Show relevant decompiled C code, addresses, and cross-references.
- Explain findings in clear, technical language appropriate for a
  reverse engineer.
- If context specifies a repo and program, use those for tool calls.
- When you cannot determine something from the tools, say so explicitly.

Keep responses focused and actionable. Prefer precision over verbosity.\
"""

# Tools excluded from the chat agent to prevent recursion
_EXCLUDED_TOOLS = {"chat_with_ollama"}


# ---------------------------------------------------------------------------
# Ollama tool-schema builder
# ---------------------------------------------------------------------------

def _build_ollama_tools() -> list[dict]:
    """Convert the MCP tool registry into Ollama function-calling format.

    Returns a list of Ollama tool descriptors with JSON-schema parameters
    derived from each tool's ``execute()`` signature.
    """
    from .tools import TOOL_REGISTRY, get_all_tools

    if not TOOL_REGISTRY:
        get_all_tools()

    tools: list[dict] = []
    for name, tool_cls in TOOL_REGISTRY.items():
        if name in _EXCLUDED_TOOLS:
            continue

        tool = tool_cls()
        sig = inspect.signature(tool.execute)
        properties: dict[str, dict] = {}
        required: list[str] = []

        for pname, param in sig.parameters.items():
            if pname == "self":
                continue

            annotation = param.annotation
            json_type = "string"
            if annotation is int:
                json_type = "integer"
            elif annotation is float:
                json_type = "number"
            elif annotation is bool:
                json_type = "boolean"

            properties[pname] = {
                "type": json_type,
                "description": f"Parameter: {pname}",
            }

            if param.default is inspect.Parameter.empty:
                required.append(pname)

        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool.description,
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    },
                },
            }
        )

    return tools


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

async def _execute_tool_call(name: str, arguments: dict[str, Any]) -> dict:
    """Execute a registered MCP tool by name and return its result as a dict."""
    from .tools import TOOL_REGISTRY

    tool_cls = TOOL_REGISTRY.get(name)
    if tool_cls is None:
        return {"error": f"Unknown tool: {name}"}

    if name in _EXCLUDED_TOOLS:
        return {"error": f"Tool '{name}' is not available in chat agent mode"}

    try:
        tool = tool_cls()
        result = await tool.execute(**arguments)
        if hasattr(result, "model_dump"):
            return result.model_dump(mode="json")
        if isinstance(result, dict):
            return result
        return {"result": str(result)}
    except Exception as e:
        logger.error("Tool %s execution failed: %s", name, e)
        return {"error": f"Tool {name} failed: {str(e)}"}


# ---------------------------------------------------------------------------
# Main chat function
# ---------------------------------------------------------------------------

async def chat(
    message: str,
    context: dict[str, Any] | None = None,
    conversation_id: str | None = None,
    model: str | None = None,
    max_turns: int = 8,
) -> dict:
    """Run the Ollama chat agent loop.

    Args:
        message: User's natural-language question or instruction.
        context: Optional dict with keys like ``repo``, ``program``,
            ``function``, ``address`` to scope the conversation.
        conversation_id: Opaque string for multi-turn threading.
            A new ID is generated if not provided.
        model: Ollama model override (defaults to ``settings.ollama_model``).
        max_turns: Maximum agent-loop iterations before returning.

    Returns:
        dict with keys: response, tools_called, conversation_id.
    """
    start = time.time()
    conversation_id = conversation_id or str(uuid.uuid4())
    model = model or settings.ollama_model
    context = context or {}

    logger.info(
        "Chat request [%s]: model=%s message=%.80s",
        conversation_id,
        model,
        message,
    )

    # Build context-aware system prompt
    system_content = SYSTEM_PROMPT
    if context:
        ctx_parts = []
        if context.get("repo"):
            ctx_parts.append(f"Repository: {context['repo']}")
        if context.get("program"):
            ctx_parts.append(f"Program: {context['program']}")
        if context.get("function"):
            ctx_parts.append(f"Current function: {context['function']}")
        if context.get("address"):
            ctx_parts.append(f"Current address: {context['address']}")
        if ctx_parts:
            system_content += "\n\nCurrent context:\n" + "\n".join(ctx_parts)

    # Retrieve or create conversation history
    messages = _get_conversation(conversation_id)

    # Inject system prompt at the start if this is a new conversation
    if not messages:
        messages.append({"role": "system", "content": system_content})

    # Append the user message
    messages.append({"role": "user", "content": message})

    # Build Ollama tool descriptors
    ollama_tools = _build_ollama_tools()

    tools_called: list[str] = []
    turns_used = 0

    async with httpx.AsyncClient(timeout=120.0) as client:
        for turn in range(max_turns):
            turns_used = turn + 1
            logger.debug("Agent loop turn %d/%d", turns_used, max_turns)

            try:
                resp = await client.post(
                    f"{settings.ollama_url}/api/chat",
                    json={
                        "model": model,
                        "messages": messages,
                        "tools": ollama_tools,
                        "stream": False,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as e:
                logger.error("Ollama API error: %s", e)
                duration_ms = (time.time() - start) * 1000
                return {
                    "response": (
                        "I was unable to reach the language model. "
                        "Please check the Ollama service."
                    ),
                    "tools_called": tools_called,
                    "conversation_id": conversation_id,
                    "turns_used": turns_used,
                    "duration_ms": duration_ms,
                    "error": str(e),
                }

            assistant_msg = data.get("message", {})
            messages.append(assistant_msg)

            # Check for tool calls
            tool_calls = assistant_msg.get("tool_calls")
            if not tool_calls:
                # No tool calls -- model gave a final answer
                break

            # Execute each tool call and feed results back
            for tc in tool_calls:
                func_info = tc.get("function", {})
                tool_name = func_info.get("name", "")
                arguments = func_info.get("arguments", {})

                logger.info(
                    "Agent calling tool: %s(%s)",
                    tool_name,
                    arguments,
                )
                tools_called.append(tool_name)

                result = await _execute_tool_call(tool_name, arguments)

                messages.append(
                    {
                        "role": "tool",
                        "content": str(result),
                    }
                )

    # Extract final assistant response
    final_response = ""
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and msg.get("content"):
            final_response = msg["content"]
            break

    if not final_response:
        final_response = (
            "I processed your request but could not generate a text response."
        )

    duration_ms = (time.time() - start) * 1000
    logger.info(
        "Chat complete [%s]: %d turns, %d tool calls, %.0f ms",
        conversation_id,
        turns_used,
        len(tools_called),
        duration_ms,
    )

    return {
        "response": final_response,
        "tools_called": tools_called,
        "conversation_id": conversation_id,
        "turns_used": turns_used,
        "duration_ms": duration_ms,
    }
