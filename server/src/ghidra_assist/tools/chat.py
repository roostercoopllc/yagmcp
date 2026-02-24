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

    async def execute(self, message: str, repository: str = "", program: str = "", function_name: str = "", function_address: str = "", address: str = "", decompilation: str = "", selection: str = "", conversation_id: str = "", model: str = "") -> Dict[str, Any]:
        if not message:
            return self._error("Missing required parameter: 'message'")

        # Build context from provided parameters
        context: Dict[str, str] = {}
        for key, val in [
            ("repository", repository),
            ("program", program),
            ("function_name", function_name),
            ("function_address", function_address),
            ("address", address),
            ("decompilation", decompilation),
            ("selection", selection),
        ]:
            if val:
                context[key] = str(val)

        actual_conversation_id: str = conversation_id or str(uuid.uuid4())
        actual_model: str | None = model or None

        try:
            # Lazy import to avoid circular dependency (chat_agent imports tools)
            from ghidra_assist.chat_agent import chat

            result = await chat(
                message=message,
                context=context,
                conversation_id=actual_conversation_id,
                model=actual_model,
            )

            return {
                "response": result.get("response", ""),
                "tools_called": result.get("tools_called", []),
                "conversation_id": result.get("conversation_id", actual_conversation_id),
            }

        except Exception as exc:
            self.logger.exception("ghidra_chat failed")
            return self._error(f"Chat failed: {exc}")
