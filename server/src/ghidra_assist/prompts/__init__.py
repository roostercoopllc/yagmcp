"""Prompt registry for YAGMCP.

Prompts are MCP prompt templates that can be rendered with user-supplied
arguments.  Each prompt module exposes a ``PROMPT`` instance implementing
the ``BasePrompt`` protocol.

After all prompt modules are imported the ``PROMPT_REGISTRY`` dict maps
prompt name -> instance.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Dict, Protocol

logger = logging.getLogger(__name__)


class BasePrompt(Protocol):
    """Minimal interface every prompt must satisfy."""

    name: str
    description: str

    def render(self, **kwargs: Any) -> str:
        """Return the fully-rendered prompt string."""
        ...


PROMPT_REGISTRY: Dict[str, BasePrompt] = {}

_PROMPT_MODULES = [
    "ghidra_assist.prompts.analyze_function",
    "ghidra_assist.prompts.vulnerability_scan",
    "ghidra_assist.prompts.rename_suggestions",
    "ghidra_assist.prompts.malware_classify",
]


def register_prompt(prompt: BasePrompt) -> BasePrompt:
    """Add *prompt* to the global registry.

    Raises ``ValueError`` on duplicate names so mis-configuration is caught
    at import time.
    """
    if prompt.name in PROMPT_REGISTRY:
        raise ValueError(
            f"Duplicate prompt name '{prompt.name}': "
            f"{PROMPT_REGISTRY[prompt.name]!r} and {prompt!r}"
        )
    PROMPT_REGISTRY[prompt.name] = prompt
    logger.debug("Registered prompt: %s", prompt.name)
    return prompt


def discover_prompts() -> Dict[str, BasePrompt]:
    """Import every prompt module so registrations fire.

    Returns the populated ``PROMPT_REGISTRY``.  Safe to call multiple times.
    """
    for mod in _PROMPT_MODULES:
        try:
            importlib.import_module(mod)
        except Exception:
            logger.exception("Failed to import prompt module %s", mod)
    return PROMPT_REGISTRY


def get_all_prompts() -> list[BasePrompt]:
    """Return all registered prompt instances.

    Triggers lazy discovery on first call — mirrors ``get_all_tools()``
    in the tools package.
    """
    if not PROMPT_REGISTRY:
        discover_prompts()
    return list(PROMPT_REGISTRY.values())
