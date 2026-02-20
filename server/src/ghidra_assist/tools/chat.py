"""Chat agent tool — wraps the Ollama agent loop.

Tools:
    ghidra_chat — receives context + question, runs Ollama agent loop
                  with access to all other Ghidra analysis tools.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool


@register_tool
class GhidraChat(BaseTool):
    name = "ghidra_chat"
    description = (
        "Chat with an LLM agent that has access to all Ghidra analysis tools. "
        "Send a natural language question with optional context (repository, "
        "program, function_name, address) and receive an analysis response. "
        "The agent can autonomously call tools like decompile_function, "
        "get_xrefs_to, list_strings, etc. to answer your question."
    )

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        message: str | None = kwargs.get("message")
        if not message:
            return self._error("Missing required parameter: 'message'")

        # Build context from provided parameters
        context: Dict[str, str] = {}
        for key in (
            "repository",
            "program",
            "function_name",
            "function_address",
            "address",
            "decompilation",
            "selection",
        ):
            val = kwargs.get(key)
            if val:
                context[key] = str(val)

        conversation_id: str = kwargs.get("conversation_id", str(uuid.uuid4()))
        model: str | None = kwargs.get("model")

        try:
            # Lazy import to avoid circular dependency (chat_agent imports tools)
            from ghidra_assist.chat_agent import chat

            result = await chat(
                message=message,
                context=context,
                conversation_id=conversation_id,
                model=model,
            )

            return {
                "response": result.get("response", ""),
                "tools_called": result.get("tools_called", []),
                "conversation_id": result.get("conversation_id", conversation_id),
            }

        except Exception as exc:
            self.logger.exception("ghidra_chat failed")
            return self._error(f"Chat failed: {exc}")
