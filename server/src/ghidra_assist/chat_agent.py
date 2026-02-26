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
import json
import logging
import re
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

You can also MODIFY programs:
- Rename functions (rename_function) and variables (rename_variable)
- Add or update comments (set_comment)
- Patch bytes in memory (patch_bytes) to fix instructions or data
- Rename labels/symbols (rename_label)

You have MALWARE ANALYSIS tools:
- Automated binary triage (triage_binary) -- architecture, packing,
  entropy, suspicious imports/strings in one call
- IOC extraction (extract_iocs) -- find IPs, URLs, domains, registry
  keys, file paths, and mutexes in binary strings
- Anti-analysis detection (detect_anti_analysis) -- find anti-debug,
  anti-VM, and sandbox evasion techniques with bypass suggestions
- YARA rule generation (generate_yara) -- synthesize a YARA detection
  rule from binary indicators

When the user asks for a modification in natural language (e.g.
"change the less-than to greater-than" or "rename var_1234 to counter"),
use the appropriate tool(s). For byte patching, first decompile and
disassemble the target to identify the exact instruction and opcode,
then apply the correct patch.

When analyzing malware:
- Start with triage_binary for quick orientation.
- Use extract_iocs to find C2 indicators and network artefacts.
- Use detect_anti_analysis to identify evasion techniques and suggest
  bypass patches before deeper analysis.
- After analysis, use generate_yara to create detection rules.

When answering questions:
- Use the available tools to look up concrete data before speculating.
- Show relevant decompiled C code, addresses, and cross-references.
- Explain findings in clear, technical language appropriate for a
  reverse engineer.
- When you cannot determine something from the tools, say so explicitly.

IMPORTANT — Using context automatically:
- When "Current context" is provided (Repository, Program, Function,
  Address, Decompiled code), use those values as default arguments for
  ALL tool calls without asking the user to supply them.
- Never ask the user "what is the repository?" or "what is the program?"
  if the context already contains that information.
- Execute tools immediately and report results directly. Do not show
  raw JSON or ask for confirmation before running a tool.
- If the context contains decompiled code, use it directly rather than
  calling decompile again for the same function.

IMPORTANT — Renaming variables:
- rename_variable identifies the target by NAME, not by stack offset or
  memory address. The optional "address" argument is the FUNCTION entry
  address (e.g. "0x401000"), NOT a per-variable stack offset. Never ask
  the user for stack offsets or variable addresses — you do not need them.
- Get the current variable names from the decompiled code in "Current
  context" if provided. If decompilation is not in context, call
  decompile_function first to retrieve it.
- NEVER use placeholder names like <old_name>, <variable>, or guesses.
  Only use names that literally appear in the decompiled code.
- Call rename_variable once per variable. Required arguments are:
    repository, program, old_name, new_name
  Optionally add function_name or address (function entry point) to
  help locate the function faster.
- Do NOT ask the user for information already present in context
  (repository, program, function name, address, decompiled code).
  Extract it from context and act immediately.

IMPORTANT — Tool call JSON format:
- When calling tools, emit one JSON object per tool call with this exact
  structure (all keys and string values must be properly double-quoted):
  {"name": "tool_name", "arguments": {"param": "value"}}
- Never use placeholder angle-bracket values like <address> or <old_name>.
  If you do not know a value, call a read tool first to obtain it.

Keep responses focused and actionable. Prefer precision over verbosity.\
"""

# Tools excluded from the chat agent to prevent recursion
_EXCLUDED_TOOLS = {"chat_with_ollama"}

# When decompilation is already in context the model only needs to apply edits,
# not query the binary.  Sending all 34 tool schemas adds ~5 000 tokens of
# overhead per Ollama call — a 7-8× slowdown on CPU-bound large models (20B+).
# This reduced set keeps the tool schema under ~700 tokens.
_MODIFICATION_TOOLS = {
    "rename_function",
    "rename_variable",
    "set_comment",
    "patch_bytes",
    "rename_label",
}


# ---------------------------------------------------------------------------
# Text-based tool call parser (fallback for models without native tool_calls)
# ---------------------------------------------------------------------------

def _parse_text_tool_calls(content: str) -> list[dict]:
    """Parse tool calls from model text content.

    Some models emit tool calls as JSON text in their content field rather
    than using the structured ``tool_calls`` field.  We scan for JSON objects
    that contain both ``"name"`` and ``"arguments"`` keys and treat them as
    tool invocations.

    Returns a list in the same shape as Ollama's ``tool_calls`` list so the
    rest of the agent loop can treat both paths identically.
    """
    calls: list[dict] = []
    decoder = json.JSONDecoder()

    # Strip markdown code fences so raw_decode sees clean JSON
    cleaned = re.sub(r"```(?:json)?\s*", "", content)
    cleaned = cleaned.replace("```", "")

    pos = 0
    while pos < len(cleaned):
        # Fast-forward to the next opening brace
        idx = cleaned.find("{", pos)
        if idx == -1:
            break
        try:
            obj, end_pos = decoder.raw_decode(cleaned, idx)
            pos = end_pos
            if (
                isinstance(obj, dict)
                and "name" in obj
                and "arguments" in obj
                and isinstance(obj["arguments"], dict)
            ):
                calls.append(
                    {
                        "function": {
                            "name": obj["name"],
                            "arguments": obj["arguments"],
                        }
                    }
                )
        except (json.JSONDecodeError, ValueError):
            pos = idx + 1

    return calls


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

    # Build context-aware system prompt.
    # Decompilation is intentionally kept OUT of the system message — it is
    # large and dramatically increases first-token latency on big models (20B+)
    # running on CPU.  Instead it is prepended to the user turn below so the
    # model sees it as conversation context rather than a system directive.
    system_content = SYSTEM_PROMPT
    decompilation = ""
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
        # Capture decompilation separately for injection into the user turn
        decompilation = context.get("decompilation", "")

    # Retrieve or create conversation history
    messages = _get_conversation(conversation_id)

    # Inject (or refresh) the system prompt — refresh on every turn so the
    # LLM always sees the latest Ghidra context (user may navigate between messages)
    if not messages:
        messages.append({"role": "system", "content": system_content})
    elif messages[0]["role"] == "system":
        messages[0]["content"] = system_content

    # Build the user message, prepending decompilation as inline context so it
    # stays in the user turn (not the system prompt) to keep first-token latency low.
    if decompilation:
        func_name = context.get("function", "current function") if context else "current function"
        user_content = (
            f"[Decompiled code of {func_name}]\n```c\n{decompilation}\n```\n\n"
            f"{message}"
        )
    else:
        user_content = message
    messages.append({"role": "user", "content": user_content})

    # Build Ollama tool descriptors.
    # When decompilation is already in context we only need modification tools
    # (~700 tokens vs ~5 000 tokens for all 34 tools).  Fewer tokens = much
    # faster first-token latency on CPU-bound large models.
    all_tools = _build_ollama_tools()
    if decompilation:
        ollama_tools = [
            t for t in all_tools
            if t["function"]["name"] in _MODIFICATION_TOOLS
        ]
        logger.debug(
            "Decompilation context present: using %d modification tools (was %d)",
            len(ollama_tools),
            len(all_tools),
        )
    else:
        ollama_tools = all_tools

    tools_called: list[str] = []
    turns_used = 0
    # Tracks whether this model rejected native tool calling and must run without tools.
    no_tools = False
    # Loop detection: track last failed tool call to break infinite retry loops.
    _last_failed_call: str = ""
    _consecutive_failures: int = 0

    # Per-call read timeout from settings (default 300s).
    # Large models (20B+) with big decompilation contexts can take >180s on first load.
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=10.0,
            read=float(settings.ollama_timeout),
            write=10.0,
            pool=5.0,
        )
    ) as client:
        for turn in range(max_turns):
            turns_used = turn + 1
            logger.debug("Agent loop turn %d/%d", turns_used, max_turns)

            payload: dict = {
                "model": model,
                "messages": messages,
                "stream": False,
            }
            if not no_tools:
                payload["tools"] = ollama_tools

            try:
                resp = await client.post(
                    f"{settings.ollama_url}/api/chat",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (400, 422) and not no_tools:
                    # Model doesn't support native tool calling (e.g. gpt-oss, some llama
                    # variants).  Drop the tools field and rely on the text-based parser.
                    logger.warning(
                        "Model %s rejected tool spec (HTTP %d); retrying without tools",
                        model,
                        e.response.status_code,
                    )
                    no_tools = True
                    payload.pop("tools", None)
                    try:
                        resp = await client.post(
                            f"{settings.ollama_url}/api/chat",
                            json=payload,
                        )
                        resp.raise_for_status()
                        data = resp.json()
                    except httpx.HTTPError as retry_err:
                        logger.error("Ollama API error (no-tools retry): %s", retry_err)
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
                            "error": str(retry_err),
                        }
                else:
                    logger.error("Ollama API error (HTTP %d): %s", e.response.status_code, e)
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

            # Check for structured tool calls (native Ollama function calling)
            tool_calls = assistant_msg.get("tool_calls")
            text_based = False

            if not tool_calls:
                # Fallback: parse JSON tool calls from text content.
                # Some models (qwen2.5-coder etc.) write tool invocations as
                # JSON in their content field instead of using tool_calls.
                content = assistant_msg.get("content", "")
                if content:
                    tool_calls = _parse_text_tool_calls(content)
                    if tool_calls:
                        text_based = True
                        logger.debug(
                            "Parsed %d text-based tool calls from content",
                            len(tool_calls),
                        )
                    else:
                        # Genuinely no tool calls -- model gave a final answer
                        break
                else:
                    break

            # Execute each tool call and feed results back
            for tc in tool_calls:
                func_info = tc.get("function", {})
                tool_name = func_info.get("name", "")
                arguments = func_info.get("arguments", {})

                # Some models prefix tool names with "functions." — strip it.
                if tool_name.startswith("functions."):
                    tool_name = tool_name[len("functions."):]

                logger.info(
                    "Agent calling tool: %s(%s)",
                    tool_name,
                    arguments,
                )
                tools_called.append(tool_name)

                result = await _execute_tool_call(tool_name, arguments)

                # Loop detection: if the same tool+args fail twice in a row,
                # break the agentic loop so the model can give a text response
                # instead of burning all remaining turns retrying.
                call_sig = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
                if "error" in result:
                    if call_sig == _last_failed_call:
                        _consecutive_failures += 1
                    else:
                        _last_failed_call = call_sig
                        _consecutive_failures = 1
                    if _consecutive_failures >= 2:
                        logger.warning(
                            "Tool %s failed twice with same args; breaking loop",
                            tool_name,
                        )
                        # Inject a final user nudge so the model summarises
                        messages.append({
                            "role": "user",
                            "content": (
                                f"[Tool result for {tool_name}]: {json.dumps(result)}\n\n"
                                "The tool is unavailable in this environment. "
                                "Please summarise what changes you would make and stop calling tools."
                            ),
                        })
                        # Force exit of both loops
                        tool_calls = []
                        turns_used = max_turns  # exhausts outer loop
                        break
                else:
                    _last_failed_call = ""
                    _consecutive_failures = 0

                if text_based:
                    # For text-based tool calls use a user message so models
                    # that don't understand the "tool" role still see the result
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"[Tool result for {tool_name}]: {json.dumps(result)}"
                            ),
                        }
                    )
                else:
                    messages.append(
                        {
                            "role": "tool",
                            "content": str(result),
                        }
                    )

    # Extract final assistant response.
    # Skip messages whose entire content is raw JSON tool calls -- those were
    # emitted by models that don't use the native tool_calls field.  A real
    # prose response never starts with a bare "{".
    final_response = ""
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and msg.get("content"):
            content = msg["content"]
            if content.strip().startswith("{") and _parse_text_tool_calls(content):
                continue  # This was a text-based tool call message, not prose
            final_response = content
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
