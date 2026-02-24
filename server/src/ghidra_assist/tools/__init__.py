"""Ghidra-Assist tool registry with auto-discovery.

Tools self-register via the ``@register_tool`` class decorator.  After all
tool modules are imported the ``TOOL_REGISTRY`` dict maps tool name -> class.

To add a new tool:
1. Create a module in this package with a class inheriting from BaseTool.
2. Apply the ``@register_tool`` decorator to the class.
3. Add the module to the import list inside ``_import_all()``.
"""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING, Dict, Type

if TYPE_CHECKING:
    from .base import BaseTool

logger = logging.getLogger(__name__)

TOOL_REGISTRY: Dict[str, Type["BaseTool"]] = {}

_TOOL_MODULES = [
    "ghidra_assist.tools.programs",
    "ghidra_assist.tools.functions",
    "ghidra_assist.tools.xrefs",
    "ghidra_assist.tools.strings",
    "ghidra_assist.tools.data_types",
    "ghidra_assist.tools.comments",
    "ghidra_assist.tools.modifications",
    "ghidra_assist.tools.triage",
    "ghidra_assist.tools.ioc_extract",
    "ghidra_assist.tools.anti_analysis",
    "ghidra_assist.tools.yara_gen",
    "ghidra_assist.tools.string_tracker",
    "ghidra_assist.tools.pattern_detector",
    "ghidra_assist.tools.type_inference",
    "ghidra_assist.tools.binary_compare",
    "ghidra_assist.tools.call_graph",
    "ghidra_assist.tools.chat",
]


def register_tool(cls: Type["BaseTool"]) -> Type["BaseTool"]:
    """Class decorator that adds *cls* to the global tool registry.

    The class must expose a ``name`` attribute (str).  Duplicate names
    raise ``ValueError`` at import time so mis-configuration is caught early.
    """
    name = getattr(cls, "name", None)
    if name is None:
        raise ValueError(f"{cls.__qualname__} is missing a 'name' class attribute")
    if name in TOOL_REGISTRY:
        raise ValueError(
            f"Duplicate tool name '{name}': "
            f"{TOOL_REGISTRY[name].__qualname__} and {cls.__qualname__}"
        )
    TOOL_REGISTRY[name] = cls
    logger.debug("Registered tool: %s -> %s", name, cls.__qualname__)
    return cls


def _import_all() -> None:
    """Import every tool module so ``@register_tool`` decorators fire."""
    for mod in _TOOL_MODULES:
        try:
            importlib.import_module(mod)
        except Exception:
            logger.exception("Failed to import tool module %s", mod)


def get_all_tools() -> list[Type["BaseTool"]]:
    """Return all registered tool classes for FastMCP registration.

    Triggers a lazy import of every tool module on first call.
    """
    if not TOOL_REGISTRY:
        _import_all()
    return list(TOOL_REGISTRY.values())


__all__ = ["TOOL_REGISTRY", "register_tool", "get_all_tools"]
